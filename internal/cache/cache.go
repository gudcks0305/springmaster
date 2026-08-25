// Package cache stores completed analysis results on local disk.
package cache

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	entrySchemaVersion      = 2
	markerSchemaVersion     = 1
	markerName              = ".springmaster-cache-owner-v1"
	markerNonceBytes        = 32
	maxEntryBytes           = 32 << 20
	maxMarkerBytes          = 512
	markerOpenRetryCount    = 40
	markerOpenRetryInterval = 5 * time.Millisecond
)

// Store is a filesystem-backed analysis result cache.
type Store struct {
	root       string
	rootInfo   os.FileInfo
	marker     ownershipMarker
	markerInfo os.FileInfo
}

type entry struct {
	SchemaVersion int             `json:"schemaVersion"`
	Key           string          `json:"key"`
	Provenance    string          `json:"provenance"`
	Value         json.RawMessage `json:"value"`
}

type ownershipMarker struct {
	SchemaVersion int    `json:"schemaVersion"`
	OwnerUID      int    `json:"ownerUID"`
	Nonce         string `json:"nonce"`
}

var errMarkerMissing = errors.New("cache ownership marker is missing")

// Open creates a new dedicated cache leaf or opens a previously marked private
// cache leaf. It never changes permissions on a directory it did not create.
func Open(root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("cache root is required")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve cache root: %w", err)
	}
	absRoot = filepath.Clean(absRoot)

	created, err := createCacheLeaf(absRoot)
	if err != nil {
		return nil, err
	}
	if created {
		return openNewStore(absRoot)
	}
	for attempt := 0; attempt <= markerOpenRetryCount; attempt++ {
		store, err := openExistingStore(absRoot)
		if err == nil {
			return store, nil
		}
		if !errors.Is(err, errMarkerMissing) || attempt == markerOpenRetryCount {
			return nil, err
		}
		time.Sleep(markerOpenRetryInterval)
	}
	return nil, errors.New("open cache root")
}

func createCacheLeaf(root string) (bool, error) {
	err := os.Mkdir(root, 0o700)
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, fmt.Errorf("create cache root: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		return false, fmt.Errorf("create cache root parent: %w", err)
	}
	if err := os.Mkdir(root, 0o700); err == nil {
		return true, nil
	} else if errors.Is(err, os.ErrExist) {
		return false, nil
	} else {
		return false, fmt.Errorf("create cache root: %w", err)
	}
}

func openNewStore(root string) (*Store, error) {
	canonicalRoot, openedRoot, rootInfo, err := openRoot(root, true)
	if err != nil {
		return nil, err
	}
	defer openedRoot.Close()
	if empty, err := rootIsEmpty(openedRoot); err != nil {
		return nil, err
	} else if !empty {
		return nil, errors.New("new cache root is unexpectedly non-empty")
	}
	marker, markerInfo, err := createMarker(openedRoot)
	if err != nil {
		return nil, err
	}
	if !rootStillMatches(canonicalRoot, rootInfo) {
		return nil, errors.New("cache root changed while opening")
	}
	return &Store{root: canonicalRoot, rootInfo: rootInfo, marker: marker, markerInfo: markerInfo}, nil
}

func openExistingStore(root string) (*Store, error) {
	canonicalRoot, openedRoot, rootInfo, err := openRoot(root, false)
	if err != nil {
		return nil, err
	}
	defer openedRoot.Close()
	marker, markerInfo, err := readMarker(openedRoot, ownershipMarker{}, nil)
	if err != nil {
		return nil, err
	}
	if !rootStillMatches(canonicalRoot, rootInfo) {
		return nil, errors.New("cache root changed while opening")
	}
	return &Store{root: canonicalRoot, rootInfo: rootInfo, marker: marker, markerInfo: markerInfo}, nil
}

func openRoot(root string, created bool) (string, *os.Root, os.FileInfo, error) {
	entryInfo, err := os.Lstat(root)
	if err != nil {
		return "", nil, nil, fmt.Errorf("stat cache root: %w", err)
	}
	if !safeDirectoryInfo(entryInfo, !created) {
		return "", nil, nil, errors.New("cache root must be an owned private directory")
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", nil, nil, fmt.Errorf("canonicalize cache root: %w", err)
	}
	canonicalRoot, err = filepath.Abs(canonicalRoot)
	if err != nil {
		return "", nil, nil, fmt.Errorf("make canonical cache root absolute: %w", err)
	}
	canonicalRoot = filepath.Clean(canonicalRoot)
	canonicalInfo, err := os.Lstat(canonicalRoot)
	if err != nil || !safeDirectoryInfo(canonicalInfo, !created) || !os.SameFile(entryInfo, canonicalInfo) {
		return "", nil, nil, errors.New("cache root changed while opening")
	}
	openedRoot, err := os.OpenRoot(canonicalRoot)
	if err != nil {
		return "", nil, nil, fmt.Errorf("open cache root: %w", err)
	}
	openedInfo, err := openedRoot.Stat(".")
	if err != nil || !openedInfo.IsDir() || !ownedByCurrentUser(openedInfo) || !os.SameFile(canonicalInfo, openedInfo) {
		openedRoot.Close()
		return "", nil, nil, errors.New("cache root changed while opening")
	}
	if created {
		if err := setNewRootPrivate(openedRoot); err != nil {
			openedRoot.Close()
			return "", nil, nil, err
		}
		openedInfo, err = openedRoot.Stat(".")
		if err != nil || !safeDirectoryInfo(openedInfo, true) {
			openedRoot.Close()
			return "", nil, nil, errors.New("new cache root is not private")
		}
	}
	if !rootStillMatches(canonicalRoot, openedInfo) {
		openedRoot.Close()
		return "", nil, nil, errors.New("cache root changed while opening")
	}
	return canonicalRoot, openedRoot, openedInfo, nil
}

func setNewRootPrivate(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open new cache root: %w", err)
	}
	defer directory.Close()
	if err := directory.Chmod(0o700); err != nil {
		return fmt.Errorf("make new cache root private: %w", err)
	}
	return nil
}

func rootIsEmpty(root *os.Root) (bool, error) {
	directory, err := root.Open(".")
	if err != nil {
		return false, fmt.Errorf("open new cache root: %w", err)
	}
	defer directory.Close()
	entries, err := directory.ReadDir(1)
	if errors.Is(err, io.EOF) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect new cache root: %w", err)
	}
	return len(entries) == 0, nil
}

func rootStillMatches(root string, expected os.FileInfo) bool {
	info, err := os.Lstat(root)
	return err == nil && safeDirectoryInfo(info, true) && os.SameFile(expected, info)
}

// Key deterministically combines every input that affects an analysis result.
func Key(analyzerVersion, contentHash, mode, ruleConfigHash string) string {
	digest := sha256.New()
	writeKeyPart(digest, "version", analyzerVersion)
	writeKeyPart(digest, "content", contentHash)
	writeKeyPart(digest, "mode", mode)
	writeKeyPart(digest, "rules", ruleConfigHash)
	return "analysis-v1-" + hex.EncodeToString(digest.Sum(nil))
}

// Get returns a cached JSON result. A missing entry is not an error.
func (store *Store) Get(ctx context.Context, key string) (json.RawMessage, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if err := validKey(key); err != nil {
		return nil, false, err
	}
	root, err := store.openValidatedRoot()
	if err != nil {
		return nil, false, err
	}
	defer root.Close()
	name := store.nameFor(key)
	entryInfo, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("inspect cache entry: %w", err)
	}
	if !safeEntryInfo(entryInfo) {
		return nil, false, nil
	}
	file, err := root.Open(name)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("open cache entry: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !safeEntryInfo(openedInfo) || !os.SameFile(entryInfo, openedInfo) {
		return nil, false, nil
	}

	contents, err := io.ReadAll(io.LimitReader(file, maxEntryBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read cache entry: %w", err)
	}
	if len(contents) > maxEntryBytes {
		return nil, false, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	var cached entry
	if err := json.Unmarshal(contents, &cached); err != nil {
		return nil, false, nil
	}
	if cached.SchemaVersion != entrySchemaVersion || cached.Key != key || cached.Provenance != store.marker.Nonce || !json.Valid(cached.Value) {
		return nil, false, nil
	}
	postInfo, err := root.Lstat(name)
	if err != nil || !safeEntryInfo(postInfo) || !os.SameFile(openedInfo, postInfo) {
		return nil, false, nil
	}
	return append(json.RawMessage(nil), cached.Value...), true, nil
}

// Put atomically replaces key with one valid JSON result.
func (store *Store) Put(ctx context.Context, key string, value json.RawMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validKey(key); err != nil {
		return err
	}
	if !json.Valid(value) {
		return errors.New("cache value must be valid JSON")
	}
	contents, err := json.Marshal(entry{SchemaVersion: entrySchemaVersion, Key: key, Provenance: store.marker.Nonce, Value: value})
	if err != nil {
		return fmt.Errorf("encode cache entry: %w", err)
	}
	if len(contents) > maxEntryBytes {
		return fmt.Errorf("cache entry exceeds %d bytes", maxEntryBytes)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	root, err := store.openValidatedRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	temporaryName, err := newTemporaryName()
	if err != nil {
		return err
	}
	temporary, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create temporary cache entry: %w", err)
	}
	defer root.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("set cache entry permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write cache entry: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync cache entry: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close cache entry: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := root.Rename(temporaryName, store.nameFor(key)); err != nil {
		return fmt.Errorf("atomically replace cache entry: %w", err)
	}
	return syncDirectory(root)
}

func (store *Store) pathFor(key string) string {
	return filepath.Join(store.root, store.nameFor(key))
}

func (store *Store) nameFor(key string) string {
	digest := sha256.Sum256([]byte(key))
	return hex.EncodeToString(digest[:]) + ".json"
}

func validKey(key string) error {
	if key == "" {
		return errors.New("cache key is required")
	}
	return nil
}

func writeKeyPart(digest io.Writer, name, value string) {
	_, _ = fmt.Fprintf(digest, "%s:%d:", name, len(value))
	_, _ = io.WriteString(digest, value)
	_, _ = io.WriteString(digest, "\n")
}

func (store *Store) openValidatedRoot() (*os.Root, error) {
	if store == nil || store.root == "" || store.rootInfo == nil || store.markerInfo == nil {
		return nil, errors.New("cache store is not initialized")
	}
	info, err := os.Lstat(store.root)
	if err != nil || !safeDirectoryInfo(info, true) || !os.SameFile(store.rootInfo, info) {
		return nil, errors.New("cache root is unsafe or was replaced")
	}
	root, err := os.OpenRoot(store.root)
	if err != nil {
		return nil, fmt.Errorf("open cache root: %w", err)
	}
	openedInfo, err := root.Stat(".")
	if err != nil || !safeDirectoryInfo(openedInfo, true) || !os.SameFile(store.rootInfo, openedInfo) {
		root.Close()
		return nil, errors.New("cache root changed while opening")
	}
	if _, _, err := readMarker(root, store.marker, store.markerInfo); err != nil {
		root.Close()
		return nil, fmt.Errorf("cache ownership marker is unsafe or was replaced: %w", err)
	}
	return root, nil
}

func safeEntryInfo(info os.FileInfo) bool {
	return safePrivateRegularFile(info) && ownedByCurrentUser(info)
}

func safeDirectoryInfo(info os.FileInfo, requirePrivate bool) bool {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !info.IsDir() || !ownedByCurrentUser(info) {
		return false
	}
	return !requirePrivate || info.Mode().Perm() == 0o700
}

func safePrivateRegularFile(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 && info.Mode().Perm() == 0o600
}

func createMarker(root *os.Root) (ownershipMarker, os.FileInfo, error) {
	marker, err := newMarker()
	if err != nil {
		return ownershipMarker{}, nil, err
	}
	contents, err := json.Marshal(marker)
	if err != nil {
		return ownershipMarker{}, nil, fmt.Errorf("encode cache ownership marker: %w", err)
	}
	temporaryName, err := newTemporaryMarkerName()
	if err != nil {
		return ownershipMarker{}, nil, err
	}
	temporary, err := root.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ownershipMarker{}, nil, fmt.Errorf("create cache ownership marker: %w", err)
	}
	defer root.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return ownershipMarker{}, nil, fmt.Errorf("set cache ownership marker permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return ownershipMarker{}, nil, fmt.Errorf("write cache ownership marker: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return ownershipMarker{}, nil, fmt.Errorf("sync cache ownership marker: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return ownershipMarker{}, nil, fmt.Errorf("close cache ownership marker: %w", err)
	}
	if err := root.Rename(temporaryName, markerName); err != nil {
		return ownershipMarker{}, nil, fmt.Errorf("install cache ownership marker: %w", err)
	}
	if err := syncDirectory(root); err != nil {
		return ownershipMarker{}, nil, err
	}
	verified, info, err := readMarker(root, marker, nil)
	if err != nil {
		return ownershipMarker{}, nil, fmt.Errorf("verify cache ownership marker: %w", err)
	}
	return verified, info, nil
}

func readMarker(root *os.Root, expected ownershipMarker, expectedInfo os.FileInfo) (ownershipMarker, os.FileInfo, error) {
	info, err := root.Lstat(markerName)
	if errors.Is(err, os.ErrNotExist) {
		return ownershipMarker{}, nil, errMarkerMissing
	}
	if err != nil {
		return ownershipMarker{}, nil, fmt.Errorf("inspect cache ownership marker: %w", err)
	}
	if !safeEntryInfo(info) || (expectedInfo != nil && !os.SameFile(expectedInfo, info)) {
		return ownershipMarker{}, nil, errors.New("cache ownership marker is unsafe or was replaced")
	}
	file, err := root.Open(markerName)
	if err != nil {
		return ownershipMarker{}, nil, fmt.Errorf("open cache ownership marker: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !safeEntryInfo(openedInfo) || !os.SameFile(info, openedInfo) {
		return ownershipMarker{}, nil, errors.New("cache ownership marker changed while opening")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxMarkerBytes+1))
	if err != nil {
		return ownershipMarker{}, nil, fmt.Errorf("read cache ownership marker: %w", err)
	}
	if len(contents) > maxMarkerBytes {
		return ownershipMarker{}, nil, errors.New("cache ownership marker is too large")
	}
	var marker ownershipMarker
	if err := json.Unmarshal(contents, &marker); err != nil || !validMarker(marker) {
		return ownershipMarker{}, nil, errors.New("cache ownership marker is invalid")
	}
	if expected != (ownershipMarker{}) && marker != expected {
		return ownershipMarker{}, nil, errors.New("cache ownership marker contents changed")
	}
	postInfo, err := root.Lstat(markerName)
	if err != nil || !safeEntryInfo(postInfo) || !os.SameFile(openedInfo, postInfo) {
		return ownershipMarker{}, nil, errors.New("cache ownership marker changed while reading")
	}
	return marker, postInfo, nil
}

func newMarker() (ownershipMarker, error) {
	var nonce [markerNonceBytes]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ownershipMarker{}, fmt.Errorf("create cache ownership marker nonce: %w", err)
	}
	return ownershipMarker{
		SchemaVersion: markerSchemaVersion,
		OwnerUID:      os.Geteuid(),
		Nonce:         hex.EncodeToString(nonce[:]),
	}, nil
}

func validMarker(marker ownershipMarker) bool {
	if marker.SchemaVersion != markerSchemaVersion || marker.OwnerUID != os.Geteuid() || len(marker.Nonce) != markerNonceBytes*2 {
		return false
	}
	_, err := hex.DecodeString(marker.Nonce)
	return err == nil
}

func newTemporaryName() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("create temporary cache entry name: %w", err)
	}
	return ".entry-" + hex.EncodeToString(token[:]), nil
}

func newTemporaryMarkerName() (string, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", fmt.Errorf("create temporary cache marker name: %w", err)
	}
	return ".marker-" + hex.EncodeToString(token[:]), nil
}

func syncDirectory(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open cache directory for sync: %w", err)
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync cache directory: %w", err)
	}
	return nil
}

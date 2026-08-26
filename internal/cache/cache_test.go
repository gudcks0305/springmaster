package cache

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "cache"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestStoreRoundTripUsesSafeAtomicEntryName(t *testing.T) {
	store := newTestStore(t)
	key := "../../outside/entry"
	value := json.RawMessage("{\n  \"findingCount\": 2,\n  \"status\": \"completed\"\n}")
	wantValue := json.RawMessage(`{"findingCount":2,"status":"completed"}`)
	if err := store.Put(context.Background(), key, value); err != nil {
		t.Fatalf("Put() error = %v", err)
	}
	got, hit, err := store.Get(context.Background(), key)
	if err != nil || !hit {
		t.Fatalf("Get() = (%s, %t, %v), want cache hit", got, hit, err)
	}
	if string(got) != string(wantValue) {
		t.Errorf("Get() = %s, want compact %s", got, wantValue)
	}
	entries, err := os.ReadDir(store.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("cache entries = %#v, want marker and one JSON entry", entries)
	}
	seenMarker, seenEntry := false, false
	for _, item := range entries {
		switch item.Name() {
		case markerName:
			seenMarker = true
		default:
			seenEntry = strings.HasSuffix(item.Name(), ".json") && !strings.Contains(item.Name(), "/")
		}
	}
	if !seenMarker || !seenEntry {
		t.Errorf("cache entries = %#v, want ownership marker and one safe JSON name", entries)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(store.root), "outside")); !os.IsNotExist(err) {
		t.Errorf("unsafe key created path outside cache root: %v", err)
	}
}

func TestStoreConcurrentWritesLeaveValidJSON(t *testing.T) {
	store := newTestStore(t)
	key := Key("analyzer-1", "sha256:content", "STATIC_ONLY", "sha256:rules")
	var group sync.WaitGroup
	for index := 0; index < 16; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			value, _ := json.Marshal(map[string]int{"writer": index})
			if err := store.Put(context.Background(), key, value); err != nil {
				t.Errorf("Put() error = %v", err)
			}
		}(index)
	}
	group.Wait()

	value, hit, err := store.Get(context.Background(), key)
	if err != nil || !hit {
		t.Fatalf("Get() = (%s, %t, %v), want valid cache hit", value, hit, err)
	}
	var decoded map[string]int
	if err := json.Unmarshal(value, &decoded); err != nil || decoded["writer"] < 0 || decoded["writer"] > 15 {
		t.Errorf("Get() value = %q, decode err = %v", value, err)
	}
}

func TestOpenConcurrentCallersShareNewMarkedLeaf(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cache")
	var group sync.WaitGroup
	errors := make(chan error, 16)
	for index := 0; index < cap(errors); index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := Open(root)
			errors <- err
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent Open() error = %v", err)
		}
	}
}

func TestKeyIncludesAllInputsAndPutRejectsInvalidJSON(t *testing.T) {
	base := Key("analyzer-1", "content-1", "STATIC_ONLY", "rules-1")
	for _, changed := range []string{
		Key("analyzer-2", "content-1", "STATIC_ONLY", "rules-1"),
		Key("analyzer-1", "content-2", "STATIC_ONLY", "rules-1"),
		Key("analyzer-1", "content-1", "EXTENDED", "rules-1"),
		Key("analyzer-1", "content-1", "STATIC_ONLY", "rules-2"),
	} {
		if changed == base {
			t.Errorf("Key() omitted a result-affecting input")
		}
	}
	store := newTestStore(t)
	if err := store.Put(context.Background(), base, json.RawMessage(`not json`)); err == nil {
		t.Error("Put() accepted invalid JSON")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := store.Get(ctx, base); err == nil {
		t.Error("Get() ignored canceled context")
	}
}

func TestOpenCreatesPrivateMarkedLeafWithoutChangingExistingDirectories(t *testing.T) {
	actualParent := t.TempDir()
	if err := os.Chmod(actualParent, 0o755); err != nil {
		t.Fatal(err)
	}
	aliasParent := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(actualParent, aliasParent); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	root := filepath.Join(aliasParent, "cache")
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	wantRoot, err := filepath.EvalSymlinks(filepath.Join(actualParent, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	if store.root != wantRoot {
		t.Fatalf("canonical root = %q, want %q", store.root, wantRoot)
	}
	parentInfo, err := os.Stat(actualParent)
	if err != nil {
		t.Fatal(err)
	}
	if parentInfo.Mode().Perm() != 0o755 {
		t.Fatalf("pre-existing parent mode = %o, want unchanged 755", parentInfo.Mode().Perm())
	}
	rootInfo, err := os.Stat(store.root)
	if err != nil {
		t.Fatal(err)
	}
	if rootInfo.Mode().Perm() != 0o700 {
		t.Fatalf("new cache root mode = %o, want 700", rootInfo.Mode().Perm())
	}
	markerInfo, err := os.Lstat(filepath.Join(store.root, markerName))
	if err != nil {
		t.Fatal(err)
	}
	if !safeEntryInfo(markerInfo) {
		t.Fatalf("ownership marker info = %v, want private regular 600", markerInfo.Mode())
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatalf("reopen marked cache leaf: %v", err)
	}
	if reopened.marker.Nonce != store.marker.Nonce {
		t.Fatal("reopened cache did not retain ownership provenance")
	}
}

func TestOpenRejectsPreexistingOrUnsafeDirectoriesWithoutChangingModes(t *testing.T) {
	key := Key("analyzer", "content", "STATIC_ONLY", "rules")
	preseed, err := json.Marshal(entry{
		SchemaVersion: entrySchemaVersion,
		Key:           key,
		Provenance:    "attacker",
		Value:         json.RawMessage(`{"status":"completed"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		mode os.FileMode
		fill func(string) error
	}{
		{name: "wrong mode", mode: 0o755},
		{name: "unmarked empty", mode: 0o700},
		{name: "unmarked nonempty", mode: 0o700, fill: func(root string) error {
			return os.WriteFile(filepath.Join(root, "untrusted"), []byte("seed"), 0o600)
		}},
		{name: "preseed cache entry", mode: 0o700, fill: func(root string) error {
			return os.WriteFile(filepath.Join(root, "entry.json"), preseed, 0o600)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "cache")
			if err := os.Mkdir(root, test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(root, test.mode); err != nil {
				t.Fatal(err)
			}
			if test.fill != nil {
				if err := test.fill(root); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Open(root); err == nil {
				t.Fatal("Open() accepted a pre-existing untrusted cache directory")
			}
			info, err := os.Stat(root)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != test.mode {
				t.Fatalf("pre-existing root mode = %o, want unchanged %o", info.Mode().Perm(), test.mode)
			}
		})
	}

	trusted := newTestStore(t)
	link := filepath.Join(t.TempDir(), "cache-link")
	if err := os.Symlink(trusted.root, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("Open() accepted a symlink cache root")
	}
}

func TestGetTreatsUnsafeTamperedAndPreseededEntriesAsMiss(t *testing.T) {
	store := newTestStore(t)
	key := Key("analyzer", "content", "STATIC_ONLY", "rules")
	value := json.RawMessage(`{"status":"completed"}`)
	entryPath := store.pathFor(key)
	assertMiss := func(label string) {
		t.Helper()
		got, hit, err := store.Get(context.Background(), key)
		if err != nil || hit || got != nil {
			t.Fatalf("%s Get() = (%s, %t, %v), want clean miss", label, got, hit, err)
		}
	}

	preseed, err := json.Marshal(entry{SchemaVersion: entrySchemaVersion, Key: key, Provenance: "attacker", Value: value})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entryPath, preseed, 0o600); err != nil {
		t.Fatal(err)
	}
	assertMiss("wrong provenance")

	if err := store.Put(context.Background(), key, value); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !safeEntryInfo(info) {
		t.Fatalf("cache entry info = %v, want private regular 600", info.Mode())
	}
	if err := os.Chmod(entryPath, 0o644); err != nil {
		t.Fatal(err)
	}
	assertMiss("public permissions")

	if err := os.WriteFile(entryPath, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(entryPath, 0o600); err != nil {
		t.Fatal(err)
	}
	assertMiss("malformed JSON")

	if err := store.Put(context.Background(), key, value); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(entryPath)
	if err != nil {
		t.Fatal(err)
	}
	var validButMutable entry
	if err := json.Unmarshal(contents, &validButMutable); err != nil {
		t.Fatal(err)
	}
	validButMutable.Value = json.RawMessage(`{"status":"different"}`)
	validJSONTamper, err := json.Marshal(validButMutable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entryPath, validJSONTamper, 0o600); err != nil {
		t.Fatal(err)
	}
	assertMiss("valid JSON with mismatched value digest")

	tampered, err := json.Marshal(entry{SchemaVersion: entrySchemaVersion + 1, Key: key, Provenance: store.marker.Nonce, Value: value})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entryPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	assertMiss("wrong schema")

	outside := filepath.Join(t.TempDir(), "outside.json")
	validEntry, err := json.Marshal(entry{SchemaVersion: entrySchemaVersion, Key: key, Provenance: store.marker.Nonce, Value: value})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outside, validEntry, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(entryPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, entryPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	assertMiss("symlink entry")
	outsideContents, err := os.ReadFile(outside)
	if err != nil || string(outsideContents) != string(validEntry) {
		t.Fatalf("outside entry changed: %q, %v", outsideContents, err)
	}
}

func TestStoreRejectsTamperedOrReplacedMarker(t *testing.T) {
	store := newTestStore(t)
	key := Key("analyzer", "content", "STATIC_ONLY", "rules")
	if err := store.Put(context.Background(), key, json.RawMessage(`{"status":"completed"}`)); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(store.root, markerName)
	if err := os.WriteFile(markerPath, []byte(`{"schemaVersion":1,"ownerUID":0,"nonce":"tampered"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Get(context.Background(), key); err == nil {
		t.Fatal("Get() accepted tampered ownership marker")
	}

	replacementStore := newTestStore(t)
	replacementKey := Key("analyzer", "other-content", "STATIC_ONLY", "rules")
	if err := replacementStore.Put(context.Background(), replacementKey, json.RawMessage(`{"status":"completed"}`)); err != nil {
		t.Fatal(err)
	}
	replacement, err := newMarker()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := json.Marshal(replacement)
	if err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(replacementStore.root, "replacement-marker")
	if err := os.WriteFile(temporary, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(temporary, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, filepath.Join(replacementStore.root, markerName)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := replacementStore.Get(context.Background(), replacementKey); err == nil {
		t.Fatal("Get() accepted replaced ownership marker")
	}
}

func TestStoreRejectsReplacedCacheRoot(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "cache")
	store, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(parent, "moved")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), root); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, _, err := store.Get(context.Background(), "key"); err == nil {
		t.Fatal("Get() accepted replaced cache root")
	}
}

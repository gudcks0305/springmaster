//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package snapshot

import (
	"context"
	"errors"
	"testing"
)

func TestContentDigestFailsClosedWhenSecureTraversalUnsupported(t *testing.T) {
	_, err := ContentDigest(context.Background(), t.TempDir(), ContentOptions{})
	if !errors.Is(err, ErrSecureTraversalUnsupported) {
		t.Fatalf("ContentDigest() error = %v, want ErrSecureTraversalUnsupported", err)
	}
}

//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package snapshot

import (
	"context"
	"fmt"
)

func secureCopyTree(_ context.Context, _, _ string, _ map[string]struct{}, _ *[]Diagnostic, _ *copyState) error {
	return fmt.Errorf("%w: descriptor-relative no-follow walk unavailable", ErrSecureTraversalUnsupported)
}

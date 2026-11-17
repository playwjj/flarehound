package check

import (
	"context"
	"sync"

	"github.com/playwjj/flarehound/internal/config"
)

// Parallel runs fn for every zone with at most n running at once (SPEC
// 15, v0.8). Errors are returned per zone, in the zones' order; one zone
// failing never stops the others. n < 1 means 1.
func Parallel(ctx context.Context, zones []config.Zone, n int, fn func(context.Context, config.Zone) error) []error {
	if n < 1 {
		n = 1
	}
	errs := make([]error, len(zones))
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, z := range zones {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				errs[i] = ctx.Err()
				return
			}
			defer func() { <-sem }()
			errs[i] = fn(ctx, z)
		}()
	}
	wg.Wait()
	return errs
}

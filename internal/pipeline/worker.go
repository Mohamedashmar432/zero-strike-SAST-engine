package pipeline

import (
	"context"
	"runtime"
	"sync"

	"github.com/zerostrike/scanner/internal/walker"
)

// workerPool runs fn on each FileEntry from files using numWorkers goroutines.
// Errors from fn are sent to errs. Both channels are closed when done.
func workerPool(
	ctx context.Context,
	files <-chan walker.FileEntry,
	numWorkers int,
	fn func(walker.FileEntry) error,
	errs chan<- error,
) {
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}
	var wg sync.WaitGroup
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range files {
				if ctx.Err() != nil {
					return
				}
				if err := fn(entry); err != nil {
					select {
					case errs <- err:
					default:
					}
				}
			}
		}()
	}
	wg.Wait()
}

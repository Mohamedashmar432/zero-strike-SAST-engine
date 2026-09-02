package walker

import (
	"errors"
	"testing"
	"time"
)

// A full error channel must not block the walk goroutine: pipeline.Run only
// reads the error channel after the file channel closes, so a blocking send
// deadlocks the entire scan (no output, no error, forever).
func TestSendErrDoesNotBlockWhenChannelIsFull(t *testing.T) {
	errs := make(chan error, 1)
	errs <- errors.New("fills the buffer")

	done := make(chan struct{})
	go func() {
		sendErr(errs, errors.New("overflow"))
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sendErr blocked on a full channel — a large repo with more walk errors than the buffer holds would hang the scan forever")
	}
}

func TestSendErrDeliversWhenBufferHasRoom(t *testing.T) {
	errs := make(chan error, 1)
	want := errors.New("boom")
	sendErr(errs, want)
	if got := <-errs; !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

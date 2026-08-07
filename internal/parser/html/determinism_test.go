//go:build cgo

package html_test

import (
	"testing"

	"github.com/Mohamedashmar432/zero-strike-SAST-engine/internal/parser/html"
)

// Regression test for the scan non-determinism first recorded (unresolved) as
// the Sprint 25 "non-reproducible anomaly": identical scans returned differing
// finding sets, e.g. 6-10 findings across repeated runs over the same 12 HTML
// fixtures. Parsing the same bytes must always yield the same IR.
func TestBuildIsDeterministic(t *testing.T) {
	src := []byte(`<!DOCTYPE html>
<html>
  <body>
    <form action="http://api.example.com/login" method="post">
      <input type="password" name="pw" autocomplete="on">
      <a href="https://x.example" target="_blank">x</a>
    </form>
    <script>var a = 1;</script>
  </body>
</html>`)

	b := html.NewIRBuilder()
	f, _, err := b.Build("t.html", src)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := len(f.Root.Children)
	if want == 0 {
		t.Fatal("baseline build produced no elements")
	}

	for i := range 300 {
		f, _, err := b.Build("t.html", src)
		if err != nil {
			t.Fatalf("iteration %d: Build: %v", i, err)
		}
		if got := len(f.Root.Children); got != want {
			t.Fatalf("iteration %d: got %d elements, want %d — parse is not deterministic", i, got, want)
		}
	}
}

// The SAST scanner fans out over runtime.NumCPU() workers, each calling
// Build concurrently, so single-threaded determinism is not enough.
func TestBuildIsDeterministicConcurrently(t *testing.T) {
	src := []byte(`<html><body>
<form action="http://api.example.com/login"><input type="password" name="pw" autocomplete="on"></form>
<a href="https://x.example" target="_blank">x</a>
</body></html>`)

	base, _, err := html.NewIRBuilder().Build("t.html", src)
	if err != nil {
		t.Fatalf("baseline Build: %v", err)
	}
	want := len(base.Root.Children)

	const workers, iters = 8, 60
	errs := make(chan string, workers*iters)
	done := make(chan struct{})
	for range workers {
		go func() {
			defer func() { done <- struct{}{} }()
			b := html.NewIRBuilder()
			for range iters {
				f, _, err := b.Build("t.html", src)
				if err != nil {
					errs <- "build error: " + err.Error()
					return
				}
				if got := len(f.Root.Children); got != want {
					errs <- "element count drift under concurrency"
					return
				}
			}
		}()
	}
	for range workers {
		<-done
	}
	close(errs)
	if msg, ok := <-errs; ok {
		t.Fatalf("concurrent Build is not deterministic: %s", msg)
	}
}

// ExtractScripts reads through the same tree-sitter CST and has the same
// lifetime hazard as Build.
func TestExtractScriptsIsDeterministic(t *testing.T) {
	src := []byte(`<html><body>
<script>var a = 1;</script>
<script>eval(location.hash);</script>
</body></html>`)

	want := len(html.ExtractScripts(src))
	if want != 2 {
		t.Fatalf("baseline: got %d script blocks, want 2", want)
	}
	for i := range 300 {
		if got := len(html.ExtractScripts(src)); got != want {
			t.Fatalf("iteration %d: got %d script blocks, want %d", i, got, want)
		}
	}
}

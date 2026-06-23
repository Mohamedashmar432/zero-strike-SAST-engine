.PHONY: build test lint benchmark clean

BINARY := zerostrike
MODULE := github.com/zerostrike/scanner

build:
	go build -o $(BINARY) ./cmd/zerostrike/

test:
	go test ./... -v -count=1

test-short:
	go test ./... -short

lint:
	go vet ./...

benchmark:
	go test ./... -bench=. -benchmem -run=^$

clean:
	rm -f $(BINARY) $(BINARY).exe
	go clean -testcache

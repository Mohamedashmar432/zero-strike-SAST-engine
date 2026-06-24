.PHONY: build test test-short test-nocgo lint benchmark clean

BINARY := zerostrike
MODULE := github.com/zerostrike/scanner

build:
	go build -o $(BINARY) ./cmd/zerostrike/

test:
	go test ./... -v -count=1

test-short:
	go test ./... -short

test-nocgo:
	CGO_ENABLED=0 go test ./... -count=1

lint:
	go vet ./...

benchmark:
	go test ./... -bench=. -benchmem -run=^$

clean:
	rm -f $(BINARY) $(BINARY).exe
	go clean -testcache

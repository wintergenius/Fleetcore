# fleetcore — common developer tasks.
GO     ?= go
BINARY ?= fleetcore

.PHONY: all build test race vet fmt tidy docker clean

all: build

build:
	$(GO) build -o $(BINARY) ./cmd/fleetcore

test:
	$(GO) test ./...

## race: run the suite under the data-race detector (needs a C compiler).
race:
	CGO_ENABLED=1 $(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

tidy:
	$(GO) mod tidy

## docker: build the distroless image from deploy/Dockerfile.
docker:
	docker build -f deploy/Dockerfile -t $(BINARY):latest .

clean:
	rm -f $(BINARY) $(BINARY).exe

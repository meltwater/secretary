export GO15VENDOREXPERIMENT=1
VERSION := $(shell git describe --tags)

all: tools deps fmt build test lint

tools:
	go get -u golang.org/x/tools/cmd/cover
	go get -u golang.org/x/lint/golint
	go get -u github.com/Masterminds/glide

deps:
	glide install

# http://golang.org/cmd/go/#hdr-Run_gofmt_on_package_sources
fmt:
	go fmt ./...

build:
	 CGO_ENABLED=0 go build -o "secretary-`uname -s`-`uname -m`" \
	 -ldflags "-X main.version=${VERSION}"
	 ln -sf "secretary-`uname -s`-`uname -m`" secretary

test:
	go test -bench=. -v -coverprofile=coverage.txt -covermode=atomic

lint:
	golint

clean:
	rm -f ./secretary

docker:
	docker build -t meltwater/secretary:latest .

.PHONY: tools deps fmt build test lint clean

all: get fmt build test

get:
	go get github.com/go-errors/errors
	go get github.com/spf13/cobra
	go get github.com/stretchr/testify/assert
	go get golang.org/x/crypto/nacl/box

# http://golang.org/cmd/go/#hdr-Run_gofmt_on_package_sources
fmt:
	go fmt ./...

build:
	go build

test:
	go test -v
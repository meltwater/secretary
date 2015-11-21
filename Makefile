all: get fmt build

get:
	go get github.com/go-errors/errors
	go get github.com/spf13/cobra
	go get golang.org/x/crypto/nacl/box

# http://golang.org/cmd/go/#hdr-Run_gofmt_on_package_sources
fmt:
	go fmt ./...

build:
	go build

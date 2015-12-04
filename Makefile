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
	 CGO_ENABLED=0 go build -o "secretary-`uname -s`-`uname -m`"
	 ln -sf "secretary-`uname -s`-`uname -m`" secretary

test:
	go test -v

clean:
	rm -f ./secretary

docker:
	docker build -t mikljohansson/secretary:latest .

.PHONY: get fmt build test clean

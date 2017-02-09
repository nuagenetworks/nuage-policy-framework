all: build 

test: build
	go test -v ./...

build: dep fmt lint
	go build -v -o npctl
dep:
	go get ./...
fmt: 
	go fmt ./...

lint:
	gometalinter --disable=dupl --disable=gocyclo --deadline 300s ./... 	

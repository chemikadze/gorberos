default: datamodel/rfc4120_generated.go
	go build .
.PHONY: default

datamodel/rfc4120_generated.go: datamodel/rfc4120.asn1
	go generate -v ./...

deps:
	go get github.com/chemikadze/asn1go/cmd/asn1go
.PHONY: deps

clean:
	find . -name '*_generated.go' -exec rm '{}' \;
.PHONY: clean

test: default
	go test -v ./...
.PHONY: test
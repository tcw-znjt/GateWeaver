# GateWeaver Makefile（Windows 开发机可用 Git-Bash/GitHub Actions；fpk 终包需 Linux + fnpack）
VERSION ?= 0.1.0

.PHONY: all test build vet linux dist icons fpk clean

all: test linux

test:
	cd src && go vet ./... && go test ./...

vet:
	cd src && go vet ./...

linux:
	cd src && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
	  -ldflags "-s -w -X gateweaver/internal/api.Version=$(VERSION)" \
	  -o ../dist/gateweaver ./cmd/gateweaver

icons:
	cd src && go run ./cmd/genicon ../dist

fpk:
	bash build.sh

clean:
	rm -rf dist build

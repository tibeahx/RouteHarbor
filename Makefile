GO ?= go
.PHONY: build test check lint fmt fmt-check fmt-web fmt-web-check matrix lab clean
build:
	mkdir -p bin
	$(GO) build -trimpath -o bin/openrhp ./cmd/openrhp
	$(GO) build -trimpath -o bin/openrhp-helper ./cmd/openrhp-helper
	$(GO) build -trimpath -o bin/openrhp-node ./cmd/openrhp-node
	$(GO) build -trimpath -o bin/openrhp-release ./cmd/openrhp-release
	$(GO) build -trimpath -o bin/openrhp-continuity ./cmd/openrhp-continuity
	$(GO) build -trimpath -o bin/openrhp-relay ./cmd/openrhp-relay
test:
	$(GO) test -race ./...
check:
	$(GO) vet ./...
	python3 scripts/check-docs.py
lint:
	GO=$(GO) sh scripts/lint.sh
fmt:
	GO=$(GO) sh scripts/fmt.sh
fmt-check:
	GO=$(GO) sh scripts/fmt.sh --check
fmt-web:
	sh scripts/format-web.sh
fmt-web-check:
	sh scripts/format-web.sh --check
matrix:
	GO=$(GO) sh scripts/build-matrix.sh
lab:
	GO=$(GO) sh scripts/lab-paths.sh
	GO=$(GO) sh scripts/lab-network.sh
clean:
	rm -rf bin dist

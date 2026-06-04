.PHONY: build test clean run lint

build:
	go build -o syck .

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f syck

run: build
	./syck scan .

lint:
	golangci-lint run 2>/dev/null || echo "golangci-lint not installed"

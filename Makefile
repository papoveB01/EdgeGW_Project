.PHONY: build test run docker clean lint

BINARY=edge-gateway
DOCKER_IMAGE=edge-gateway:latest

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY) ./cmd/gateway

test:
	go test -v -race ./...

test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

run:
	go run ./cmd/gateway

docker:
	docker build -t $(DOCKER_IMAGE) .

docker-run:
	docker run --rm -p 8080:8080 \
		-e INSTITUTION_ID=TEST_INST \
		-e API_KEY=test_key \
		-e HMAC_SECRET=test_secret \
		-e BANK_SALT=test_bank_salt_32_characters_minimum \
		-e REGIONAL_PEPPER=test_pepper \
		-e HUB_API_URL=http://host.docker.internal:8012/api/v1/signals \
		$(DOCKER_IMAGE)

clean:
	rm -f $(BINARY) coverage.out coverage.html

lint:
	go vet ./...

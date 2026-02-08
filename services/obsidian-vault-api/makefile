APP := vault-api
PORT ?= 8787
ARCH ?= amd64

.PHONY: help build run docker docker-up docker-down clean

help:
	@echo ""
	@echo "Available targets:"
	@echo "  make build        Build Go binary"
	@echo "  make run          Run locally (env required)"
	@echo "  make docker       Build Docker image"
	@echo "  make docker-up    Run via docker compose"
	@echo "  make docker-down  Stop docker compose"
	@echo "  make clean        Remove binaries"
	@echo ""

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) \
		go build -trimpath -ldflags "-s -w" -o $(APP)

run:
	./$(APP)

docker:
	docker build -t $(APP) .

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

clean:
	rm -f $(APP)

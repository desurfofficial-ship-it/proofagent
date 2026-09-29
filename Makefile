.PHONY: test build api sdk-py docker-up

test:
	go test ./...

build:
	go build -o bin/proofagent-api ./services/api

api: build
	./bin/proofagent-api

sdk-py:
	pip install -e sdk/python

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down

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

e2e:
	./scripts/e2e.sh

release-check: test build
	@echo "v0.1.0 release check OK"

verify-cli:
	go build -o bin/proofagent-verify ./cmd/proofagent-verify

phase3: verify-cli
	./scripts/phase3_company_ab.sh

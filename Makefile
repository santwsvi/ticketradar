build:
	go build -o bin/ticketradar ./cmd/server

run:
	@export $(shell cat .env | xargs) && go run ./cmd/server

run-bin:
	@export $(shell cat .env | xargs) && ./bin/ticketradar

deps:
	go get gopkg.in/gomail.v2
	go get modernc.org/sqlite
	go mod tidy

test:
	go test ./...

.PHONY: build run run-bin deps test

.DEFAULT_GOAL := build

.PHONY: fmt vet build

TARGET ?= passutils

TARGET_DIR := ./cmd/$(TARGET)

fmt:
	go fmt ./...

vet: fmt
	go vet ./...

build: vet
	@echo "Building $(TARGET)..."
	go build -o ./bin/$(TARGET) $(TARGET_DIR)

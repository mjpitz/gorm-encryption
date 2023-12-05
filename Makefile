define HELP_TEXT
Welcome!

Targets:
help				provides help text
test				run tests
legal				prepends legal header to source code

endef
export HELP_TEXT

help:
	@echo "$$HELP_TEXT"

deps:
	go mod download
	cd integration && go mod download

deps/upgrade:
	go get -u ./...
	cd integration && go get -u ./...

deps/tidy:
	go mod tidy
	cd integration && go mod tidy

test:
	@go test -v -race -covermode=atomic -coverprofile=coverage.unit.txt -coverpkg=./... ./...
	@bash ./scripts/test.sh

legal: .legal
.legal:
	@git ls-files | xargs -I{} addlicense -f ./legal/header.txt -skip yaml -skip yml {}

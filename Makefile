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

test:
	go test -v -race -coverprofile=.coverprofile -covermode=atomic ./...

legal: .legal
.legal:
	git ls-files | xargs -I{} addlicense -f ./LICENSE -skip yaml -skip yml {}

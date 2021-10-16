deps:
	go mod download
	go mod verify
	go mod tidy

lint:
# format code
	gofmt -w=true -s=true -l=true .
# run basic code quality and sanity check
	golint ./...
	go vet ./...

check: lint
# ran unit tests with coverage report
	go test -v -coverprofile=cover.out ./...

test: check

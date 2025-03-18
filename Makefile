default: build

test:
	go test ./...

build:
	go build -o tflint-ruleset-oci

install: build
	mkdir -p ~/.tflint.d/plugins
	mv ./tflint-ruleset-oci ~/.tflint.d/plugins

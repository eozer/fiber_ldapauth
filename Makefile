EXAMPLES=$(patsubst %.go,%,$(wildcard examples/*.go))

test:
	go test -v -race

examples: clean-examples ${EXAMPLES}
	@echo "Done"

clean-examples:
	rm -f ${EXAMPLES}

./examples/%:
	go build -o $@ $@.go

.PHONY: test examples

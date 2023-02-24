DEST=${PWD}
BIN=trustedclient

.PHONY: all bin deps clean sim run host

all: bin

bin:
	ego-go build -o=${BIN}
	ego sign ${BIN}

sim:
	OE_SIMULATION=1 ego run ${BIN}

run:
	ego run ${BIN}

deps:
	@go get github.com/gogo/protobuf/proto
	@go install github.com/gogo/protobuf/protoc-gen-gogo
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc
	@go install github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
	@go install github.com/bufbuild/buf/cmd/buf@v1.9.0

clean:
	@rm -f $(BIN)

